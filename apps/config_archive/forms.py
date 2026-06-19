"""Formulários para o app config_archive."""

from django import forms

from apps.devices.models import Device


class NewAnalysisForm(forms.Form):
    """Formulário de nova análise via navegador."""

    device_name = forms.CharField(
        label="Nome do equipamento",
        max_length=100,
        error_messages={"required": "O nome do equipamento é obrigatório."},
    )
    vendor = forms.ChoiceField(
        label="Fabricante",
        choices=[
            ("huawei", "Huawei / VRP"),
            ("cisco_ios", "Cisco IOS / IOS-XE"),
        ],
        error_messages={"required": "Selecione um fabricante."},
    )
    raw_config = forms.CharField(
        label="Configuração bruta",
        widget=forms.Textarea(attrs={"rows": 20}),
        error_messages={"required": "A configuração não pode estar vazia."},
    )
    notes = forms.CharField(
        label="Observações",
        widget=forms.Textarea(attrs={"rows": 3}),
        required=False,
    )

    def clean_vendor(self):
        vendor = self.cleaned_data["vendor"]
        vendor_map = dict(Device.Vendor.choices)
        if vendor not in vendor_map:
            raise forms.ValidationError(
                f"Fabricante '{vendor}' não é suportado. "
                f"Suportados: {', '.join(vendor_map.keys())}"
            )
        return vendor

    def clean_device_name(self):
        name = self.cleaned_data["device_name"].strip()
        if not name:
            raise forms.ValidationError("O nome do equipamento é obrigatório.")
        return name

    def clean_raw_config(self):
        config = self.cleaned_data["raw_config"].strip()
        if not config:
            raise forms.ValidationError("A configuração não pode estar vazia.")
        return config
