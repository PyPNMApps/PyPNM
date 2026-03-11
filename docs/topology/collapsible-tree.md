# Interactive Topology Tree

This page uses a D3 collapsible tree pattern similar to the Observable example:

- https://observablehq.com/@d3/collapsible-tree

Click any node label to collapse or expand its children.

<div id="topology-tree" style="width:100%; max-width:1400px; height:760px; border:1px solid rgba(127,127,127,0.35); border-radius:10px; overflow:auto; margin: 1rem 0; background: var(--md-default-bg-color);"></div>

<script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
<script>
(function () {
  const container = document.getElementById("topology-tree");
  if (!container || typeof d3 === "undefined") return;

  const topologyData = {
    name: "CMTS",
    children: [
      {
        name: "Serving Group 101",
        children: [
          {
            name: "Downstream",
            children: [
              { name: "Channel 33 (709 MHz)" },
              { name: "Channel 34 (717 MHz)" }
            ]
          },
          {
            name: "Upstream",
            children: [
              { name: "US 4 (36.4 MHz)" },
              { name: "US 5 (43.6 MHz)" }
            ]
          },
          {
            name: "Cable Modems",
            children: [
              { name: "CM aa:bb:cc:dd:ee:ff" },
              { name: "CM aa:bb:cc:dd:ee:ff" }
            ]
          }
        ]
      },
      {
        name: "Serving Group 102",
        children: [
          {
            name: "Downstream",
            children: [{ name: "Channel 193 (841 MHz)" }]
          },
          {
            name: "Upstream",
            children: [{ name: "US 80 (31.0 MHz)" }]
          }
        ]
      }
    ]
  };

  const width = 1320;
  const dx = 26;
  const dy = 220;
  const tree = d3.tree().nodeSize([dx, dy]);
  const diagonal = d3.linkHorizontal().x((d) => d.y).y((d) => d.x);
  const root = d3.hierarchy(topologyData);
  root.x0 = 0;
  root.y0 = 0;
  root.descendants().forEach((d, i) => {
    d.id = i;
    d._children = d.children;
    if (d.depth > 1) d.children = null;
  });

  const svg = d3.create("svg")
    .attr("width", width)
    .attr("height", dx)
    .attr("viewBox", [-dy / 3, -dx, width, dx])
    .style("font", "13px sans-serif")
    .style("user-select", "none");

  const gLink = svg.append("g")
    .attr("fill", "none")
    .attr("stroke", "currentColor")
    .attr("stroke-opacity", 0.35)
    .attr("stroke-width", 1.5);

  const gNode = svg.append("g")
    .attr("cursor", "pointer")
    .attr("pointer-events", "all");

  function update(source) {
    const duration = 250;
    const nodes = root.descendants().reverse();
    const links = root.links();
    tree(root);

    let left = root;
    let right = root;
    root.eachBefore((node) => {
      if (node.x < left.x) left = node;
      if (node.x > right.x) right = node;
    });

    const height = right.x - left.x + dx * 2;

    svg.transition()
      .duration(duration)
      .attr("height", height)
      .attr("viewBox", [-dy / 3, left.x - dx, width, height]);

    const node = gNode.selectAll("g")
      .data(nodes, (d) => d.id);

    const nodeEnter = node.enter().append("g")
      .attr("transform", () => `translate(${source.y0},${source.x0})`)
      .attr("fill-opacity", 0)
      .attr("stroke-opacity", 0)
      .on("click", (event, d) => {
        d.children = d.children ? null : d._children;
        update(d);
      });

    nodeEnter.append("circle")
      .attr("r", 5)
      .attr("fill", (d) => d._children ? "#5a6fd8" : "#39c28e")
      .attr("stroke-width", 1.5)
      .attr("stroke", "currentColor");

    nodeEnter.append("text")
      .attr("dy", "0.31em")
      .attr("x", (d) => d._children ? -9 : 9)
      .attr("text-anchor", (d) => d._children ? "end" : "start")
      .text((d) => d.data.name)
      .clone(true).lower()
      .attr("stroke-linejoin", "round")
      .attr("stroke-width", 3)
      .attr("stroke", "var(--md-default-bg-color, white)");

    const nodeUpdate = node.merge(nodeEnter).transition()
      .duration(duration)
      .attr("transform", (d) => `translate(${d.y},${d.x})`)
      .attr("fill-opacity", 1)
      .attr("stroke-opacity", 1);

    const nodeExit = node.exit().transition()
      .duration(duration)
      .remove()
      .attr("transform", () => `translate(${source.y},${source.x})`)
      .attr("fill-opacity", 0)
      .attr("stroke-opacity", 0);

    const link = gLink.selectAll("path")
      .data(links, (d) => d.target.id);

    const linkEnter = link.enter().append("path")
      .attr("d", () => {
        const o = { x: source.x0, y: source.y0 };
        return diagonal({ source: o, target: o });
      });

    link.merge(linkEnter).transition()
      .duration(duration)
      .attr("d", diagonal);

    link.exit().transition()
      .duration(duration)
      .remove()
      .attr("d", () => {
        const o = { x: source.x, y: source.y };
        return diagonal({ source: o, target: o });
      });

    root.eachBefore((d) => {
      d.x0 = d.x;
      d.y0 = d.y;
    });
  }

  update(root);
  container.innerHTML = "";
  container.appendChild(svg.node());
})();
</script>
