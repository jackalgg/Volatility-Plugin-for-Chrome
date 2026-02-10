from volatility3.framework.configuration import requirements
from volatility3.framework import interfaces, renderers
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints
import re


class LinuxUrlScan(interfaces.plugins.PluginInterface):
    """Scan a Linux memory layer and carve probable URLs using regex."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the Linux image",
                optional=False
            )
        ]

    def _generator(self):
        layer_name = self.config["primary"]
        layer = self.context.layers[layer_name]

        # Raw bytes regex pattern for URLs
        url_pattern = br"https?://[^\s\"'<>]+"
        scanner = scanners.RegExScanner(url_pattern)

        # NOTE: layer.scan returns a single offset per hit
        for offset in layer.scan(context=self.context, scanner=scanner):
            # Read bytes starting at the hit
            chunk = layer.read(offset, 256, pad=True)

            # Match URL at the start of the chunk
            m = re.match(url_pattern, chunk)
            if not m:
                continue

            raw_url = m.group(0)
            url = raw_url.decode("utf-8", errors="ignore")

            # Tiny sanity guard
            if len(url) < 8:
                continue

            yield (0, (format_hints.Hex(offset), url))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("URL", str),
            ],
            self._generator(),
        )
