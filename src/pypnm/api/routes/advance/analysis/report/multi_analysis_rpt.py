# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel

from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
    TransactionCollection,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollectionModel,
)
from pypnm.api.routes.basic.abstract.analysis_report import AnalysisOutputModel
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.data_type.sysDescr import SystemDescriptor, SystemDescriptorModel
from pypnm.lib.archive.manager import ArchiveManager
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.mac_address import MacAddress, cast
from pypnm.lib.matplot.manager import MatplotManager
from pypnm.lib.types import ChannelId, JsonScalar, PathArray, PathLike, TimeStamp
from pypnm.lib.utils import Generate, TimeUnit


class MultiAnalysisRpt(ABC):
    """
    Abstact Class to manage multiple captures:
     + This class will be inherited and can support single or multiple cable modems
    """
    def __init__(self, capt_data_agg: CaptureDataAggregator) -> None:
        self.logger = logging.getLogger("MultiAnalysisRpt")

        self._capt_data_agg = capt_data_agg
        self._trans_collect:TransactionCollection = capt_data_agg.collect()
        tcm:TransactionCollectionModel = self._trans_collect.getTransactionCollectionModel()[0]

        self._png_dir: PathLike       = cast(PathLike, SystemConfigSettings.png_dir())
        self._csv_dir: PathLike       = cast(PathLike, SystemConfigSettings.csv_dir())
        self._json_dir: PathLike      = cast(PathLike, SystemConfigSettings.json_dir())
        self._archive_dir: PathLike   = cast(PathLike, SystemConfigSettings.archive_dir())

        self._group_time:TimeStamp    = Generate.time_stamp()
        self._base_filename: PathLike = ""
        self._common_analysis_model: dict[ChannelId, BaseModel] = {}

        self._mac_addresses: set[MacAddress]  = set()
        self._cmts_mac_address: MacAddress = MacAddress(MacAddress.null())
        self._sys_descr_model: SystemDescriptorModel  = tcm.device_details.system_description

        self.csv_files: list[PathLike]  = []
        self.plot_files: list[PathLike] = []
        self.json_files: list[PathLike] = []

        self.logger.info(f"MultiAnalysisRpt: MAC: {self._mac_addresses}, "
                         f"Model: {self._sys_descr_model.model_dump()}, "
                         f"GroupTime: {self._group_time}")

    def getMacAddresses(self) -> list[MacAddress]:
        """Return the cable-modem MAC address associated with this report session."""
        return self._trans_collect.getMacAddresses()

    def get_system_description(self) -> SystemDescriptor:
        """Return the device SystemDescriptor used for filenames and labeling."""
        return SystemDescriptor.load_from_dict(self._sys_descr_model.model_dump())

    def get_group_time(self) -> int:
        """Return the session/group timestamp used to namespace output filenames."""
        return self._group_time

    def to_output_model(self) -> AnalysisOutputModel:
        """
        Produce a serializable model of the generated artifacts (time, CSVs, plots, archive).

        Call this after `build_report()` to pass paths and metadata to API callers.
        """
        return AnalysisOutputModel(
            time         =   self._group_time,
            csv_files    =   self.csv_files,
            plot_files   =   self.plot_files,
            json_files   =   self.json_files,
            archive_file =   self.archive_file,)

    def create_csv_fname(self, tags: list[str] = None) -> PathLike:
        '''
        Build a CSV filename of the form:
            <csv_dir>/<mac>_<model>_<timestamp>[_TAGS].csv

        Example:
            fname = self.create_csv_fname(tags=["ch1", "rpt"])
        '''
        if tags is None:
            tags = []
        return f"{self._csv_dir}/{self.create_generic_fname(tags=tags, ext='csv')}"

    def create_png_fname(self, tags: list[str] = None) -> PathLike:
        '''
        Build a PNG filename of the form:
            <png_dir>/<mac>_<model>_<timestamp>[_TAGS].png

        Example:
            fname = self.create_png_fname(tags=["spectrum"])
        '''
        if tags is None:
            tags = []
        return f"{self._png_dir}/{self.create_generic_fname(tags=tags, ext='png')}"

    def create_json_fname(self, tags: list[str] = None) -> PathLike:
        '''
        Build a PNG filename of the form:
            <json_dir>/<mac>_<model>_<timestamp>[_TAGS].json

        Example:
            fname = self.create_json_fname(tags=["spectrum"])
        '''
        if tags is None:
            tags = []
        return f"{self._json_dir}/{self.create_generic_fname(tags=tags, ext='json')}"

    def create_archive_fname(self, tags: list[str] = None) -> PathLike:
        '''
        Build a ZIP archive filename of the form:
            <archive_dir>/<mac>_<model>_<timestamp>[_TAGS].zip

        Example:
            fname = self.create_archive_fname(tags=["bundle"])
        '''
        if tags is None:
            tags = []
        return f"{self._archive_dir}/{self.create_generic_fname(tags=tags, ext='zip')}"

    def create_generic_fname(self, tags: list[str], ext: str = "") -> str:
        """
        Generate a generic filename using the current session metadata plus tags.

        Args:
            tags: Optional descriptors to append (e.g., ["ch1", "rpt"]).
            ext:  Optional file extension (e.g., "csv", ".png").

        Returns:
            The constructed filename (no directories).

        Example:
            name = self.create_generic_fname(tags=["debug"], ext="json")
        """
        return self._generate_fname(tags=tags, ext=ext)

    def csv_manager_factory(self) -> CSVManager:
        """Return a `CSVManager` instance. Subclasses may override to customize behavior."""
        return CSVManager()

    def get_base_filename(self) -> str:
        """
        Return the base filename (no extension) derived from MAC/model/time.

        Useful when emitting multiple related files for the same report run.
        """
        return self._generate_fname()

    def build_report(self) -> Path:
        """
        Run the full report pipeline: `_process()` → CSV generation → plot rendering → ZIP.

        Returns:
            The path to the created ZIP archive.

        Typical use:
            archive = report.build_report()
            return report.to_model()
        """
        self._process()

        f:PathArray = [Path('')]

        for csv_mgr in self.create_csv():

            if not csv_mgr.write():
                self.logger.error(f"Failed to write CSV: {csv_mgr.get_path_fname()}")
                continue

            self.logger.debug(f'Wrote CSV File: {csv_mgr.get_path_fname()}')
            self.csv_files.append(csv_mgr.get_path_fname())
            f.append(csv_mgr.get_path_fname())

        for matplot_mgr in self.create_matplot():
            for fn in matplot_mgr.get_png_files():
                self.logger.debug(f'Wrote Matplotlib Figure: {fn}')
                self.plot_files.append(fn)
                f.append(fn)

        if not self.json_files:
            self.logger.warning("No JSON files were registered for the report archive.")
        else:
            f.extend(self.json_files)

        try:
            self.archive_file = ArchiveManager().zip_files(files=f, archive_path=self.create_archive_fname())

        except Exception as e:
            self.logger.error(f"Failed to create archive: {e}")

        return self.archive_file

    def _generate_fname(self, tags: list[str] = None, ext: str = "") -> str:
        """
        Construct a sanitized filename from:
          - MAC address (colon-free, lowercase)
          - device model (`system_description.model`, spaces → underscores, lowercase)
          - group timestamp
          - optional tag suffix (underscored)
          - optional extension

        Args:
            tags: Descriptive tokens to append (e.g., ["ch1", "rpt"]).
            ext:  Extension with or without leading dot.

        Returns:
            The finalized filename string (no directory).

        Example:
            self._generate_fname(tags=["ch1", "rpt"], ext="csv")
        """
        if tags is None:
            tags = []
        mac = self.getMacAddresses()[0].to_mac_format()
        model = self.get_system_description().model.replace(" ", "_").lower()
        ts = str(self.get_group_time())

        clean_tags = []
        for t in tags:
            t_clean = str(t).strip().replace(" ", "_").lower()
            if t_clean:
                clean_tags.append(t_clean)

        tag_part = f"_{'_'.join(clean_tags)}" if clean_tags else ""
        ext = ext.lstrip(".")
        ext_part = f".{ext}" if ext else ""

        return f"{mac}_{model}_{ts}{tag_part}{ext_part}"

    def getTransactionCollection(self) -> TransactionCollection:
        """Return the `TransactionCollection` instance used to collect capture files."""
        return self._trans_collect

    def register_models_for_json_archive_files(self, model:BaseModel, filename_tags: list[str], append_timestamp: bool = True) -> None:
        """Register a Pydantic model to be serialized as JSON and included in the report archive."""

        # model is a Pydantic BaseModel instance, but it can be any subclass
        # We need to make sure its initial derive is from BaseModel
        if not isinstance(model, BaseModel):
            raise TypeError("model must be a Pydantic BaseModel instance")

        if append_timestamp:
            filename_tags.append(str(Generate.time_stamp(TimeUnit.NANOSECONDS)))

        full_path_fname = self.create_json_fname(tags=filename_tags)

        JsonTransactionDb().write_json(data  = model.model_dump(),
                                       fname = Path(full_path_fname).parts[-1])

        self.json_files.append(full_path_fname)

    @abstractmethod
    def _process(self) -> None:
        """
        Populate per-channel report models from analysis results.

        Implement in subclasses:
            - Parse `self.get_analysis_model()` and/or `self.get_analysis_data()`.
            - Build models and register with:
                `self.register_common_analysis_model(channel_id, model)`.
        """
        pass

    @abstractmethod
    def create_csv(self, **kwargs: JsonScalar) -> list[CSVManager]:
        """
        Build one or more `CSVManager` instances ready to `write()`.

        Parameters
        ----------
        **kwargs : JsonScalar
            Optional configuration flags or scalar parameters (ints, floats,
            strings, booleans, or None) used by concrete implementations.

        Returns
        -------
        list[CSVManager]
            List of configured `CSVManager` instances ready to write.
        """
        return []

    @abstractmethod
    def create_matplot(self, **kwargs: JsonScalar) -> list[MatplotManager]:
        """
        Build one or more `MatplotManager` instances to render PNG figures.

        Parameters
        ----------
        **kwargs : JsonScalar
            Optional configuration flags or scalar parameters (ints, floats,
            strings, booleans, or None) used by concrete implementations.

        Returns
        -------
        list[MatplotManager]
            List of configured `MatplotManager` instances used to generate plots.
        """
        return []
