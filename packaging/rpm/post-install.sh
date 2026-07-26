if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null || :
fi

echo "Vopono daemon installed. Start it now and enable it at boot with:"
echo "  sudo systemctl enable --now vopono.service"
