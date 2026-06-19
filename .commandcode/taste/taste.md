# Taste (Continuously Learned by [CommandCode][cmd])

[cmd]: https://commandcode.ai/

# django
- Use Django templates with direct ORM queries instead of frontend frameworks (React, SPA). Confidence: 0.85
- Implement filters manually with QuerySet instead of using django-filter. Confidence: 0.70

# css
- Use only built-in CSS without external frameworks or dependencies. Confidence: 0.70

# security
- Never store real secrets, passwords, community strings, or keys in parsed_data — only flags (has_password, password_type, has_secret). Confidence: 0.85

# testing
- Create dedicated test files per feature domain (e.g., test_management.py for management/observability tests) instead of adding to monolithic test files. Confidence: 0.70

