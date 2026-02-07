# Contributing to CertSentinel

We love your input! We want to make contributing to CertSentinel as easy and transparent as possible.

## Development Process

1. Fork the repo and create your branch from `main`
2. Make your changes and add tests if applicable
3. Ensure tests pass: `python -m pytest`
4. Update documentation if needed
5. Submit a pull request

## Pull Request Process

1. Update README.md with details of changes if needed
2. Follow conventional commit format: `feat:`, `fix:`, `docs:`, `refactor:`
3. Ensure code follows PEP 8 style guide
4. Add tests for new features
5. PR will be merged once reviewed and approved

## Bug Reports

Use GitHub Issues and include:
- Clear description
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version)

## Feature Requests

Open an issue describing:
- Use case and motivation
- Proposed solution
- Alternatives considered

## Code Style

- Follow PEP 8
- Use type hints where applicable
- Write docstrings for public functions
- Keep functions focused and under 50 lines

## Testing

Run tests before submitting:
```bash
python -m pytest
python -m py_compile bot.py db.py scanner.py
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
