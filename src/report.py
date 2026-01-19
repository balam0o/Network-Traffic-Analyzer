import html  # escape HTML for safe output

def _escape(value):  # normalize values for HTML
    return html.escape(str(value))  # escape to prevent HTML injection

def _svg_throughput(series, width=800, height=200, pad=20):  # inline SVG chart
    if not series:  # handle empty data
        return f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"><text x="10" y="20">No throughput data</text></svg>'  # empty chart
    max_bps = max(item["bps"] for item in series) or 1.0  # avoid zero division
    n = len(series)  # bucket count
    if n == 1:  # single point
        xs = [pad]  # single x coordinate
    else:  # multiple points
        xs = [pad + (i * (width - 2 * pad) / (n - 1)) for i in range(n)]  # distribute x positions
    points = []  # collect polyline points
    for i, item in enumerate(series):  # build points
        x = xs[i]  # x coordinate
        y = height - pad - ((item["bps"] / max_bps) * (height - 2 * pad))  # scale y by max
        points.append(f"{x},{y}")  # add point
    polyline = " ".join(points)  # polyline points string
    return (  # svg output
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">'  # svg open
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#f8f8f8"/>'  # background
        f'<polyline fill="none" stroke="#1f77b4" stroke-width="2" points="{polyline}"/>'  # line
        f'<line x1="{pad}" y1="{pad}" x2="{pad}" y2="{height - pad}" stroke="#333" stroke-width="1"/>'  # y axis
        f'<line x1="{pad}" y1="{height - pad}" x2="{width - pad}" y2="{height - pad}" stroke="#333" stroke-width="1"/>'  # x axis
        f'</svg>'  # svg close
    )  # end svg

def render_html_report(report, out_path):  # write HTML visualization report
    tp = report.get("throughput", [])  # throughput series
    tp_sum = report.get("throughput_summary", {})  # throughput summary
    lat_sum = report.get("tcp_latency_summary", {})  # RTT summary
    loss = report.get("tcp_loss", {})  # loss stats
    html_out = [  # html lines
        "<!doctype html>",  # html doctype
        "<html>",  # html open
        "<head>",  # head open
        "<meta charset=\"utf-8\">",  # charset
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",  # responsive meta
        "<title>Network Traffic Report</title>",  # title
        "<style>body{font-family:Arial, sans-serif;margin:24px;}h1{margin-bottom:6px;}section{margin:18px 0;}table{border-collapse:collapse;}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;}code{background:#f4f4f4;padding:2px 4px;}</style>",  # inline styles
        "</head>",  # head close
        "<body>",  # body open
        "<h1>Network Traffic Report</h1>",  # title
        f"<p>Total packets: <strong>{_escape(report.get('total_packets', 0))}</strong></p>",  # total packets
        "<section>",  # section open
        "<h2>Throughput</h2>",  # section title
        _svg_throughput(tp),  # throughput svg
        f"<p>Windows: {_escape(tp_sum.get('buckets', 0))}, Avg bps: {_escape(round(tp_sum.get('avg_bps', 0.0), 2))}, Max bps: {_escape(round(tp_sum.get('max_bps', 0.0), 2))}</p>",  # throughput summary
        "</section>",  # section close
        "<section>",  # section open
        "<h2>TCP RTT (ms)</h2>",  # RTT heading
        f"<p>SYN count: {_escape(lat_sum.get('syn', {}).get('count', 0))}, min: {_escape(lat_sum.get('syn', {}).get('min_ms'))}, avg: {_escape(lat_sum.get('syn', {}).get('avg_ms'))}, max: {_escape(lat_sum.get('syn', {}).get('max_ms'))}</p>",  # SYN summary
        f"<p>DATA count: {_escape(lat_sum.get('data', {}).get('count', 0))}, min: {_escape(lat_sum.get('data', {}).get('min_ms'))}, avg: {_escape(lat_sum.get('data', {}).get('avg_ms'))}, max: {_escape(lat_sum.get('data', {}).get('max_ms'))}</p>",  # DATA summary
        "</section>",  # section close
        "<section>",  # section open
        "<h2>TCP Loss Estimate</h2>",  # loss heading
        f"<p>Retransmissions: {_escape(loss.get('retransmissions', 0))}, Total segments: {_escape(loss.get('total_segments', 0))}, Loss rate: {_escape(loss.get('loss_rate', 0.0))}</p>",  # loss summary
        "</section>",  # section close
        "</body>",  # body close
        "</html>",  # html close
    ]  # end html lines
    with open(out_path, "w", encoding="utf-8") as f:  # open output path
        f.write("\n".join(html_out))  # write html file
