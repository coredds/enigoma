# Contributing to enigoma

Thank you for considering contributing to enigoma! We welcome contributions from the community to help improve the project.

## How to Contribute

1. **Fork the Repository**: Start by forking the repository to your GitHub account.

2. **Clone Your Fork**: Clone your forked repository to your local machine.

   ```bash
   git clone https://github.com/your-username/enigoma.git
   cd enigoma
   ```

3. **Create a Branch**: Create a new branch for your feature or bug fix.

   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make Changes**: Implement your changes, ensuring you follow the project's coding standards and best practices.

5. **Run Tests and Lint**: Ensure all tests and linting pass.

   ```bash
   go test ./...
   golangci-lint run
   ```

6. **Commit Changes**: Use short, descriptive commit messages. No emojis.

   ```bash
   # Good examples:
   git commit -m "add fuzz tests for settings serialization"
   git commit -m "fix unicode plugboard deserialization"
   git commit -m "update CI workflow action versions"

   # Bad examples:
   git commit -m "Fixed stuff"
   git commit -m "🚀 Add amazing new feature"
   ```

   Rules:
   - One line, max ~50 characters
   - Start with a lowercase verb (`add`, `fix`, `update`, `remove`, `refactor`)
   - No trailing period, no emojis

7. **Push to GitHub**: Push your changes to your forked repository.

   ```bash
   git push origin feature/your-feature-name
   ```

8. **Open a Pull Request**: Open a pull request to the main repository. Provide a detailed description of your changes and any relevant information.

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project, you agree to abide by its terms.

## Reporting Issues

If you encounter any issues or have questions, please open an issue on GitHub. Provide as much detail as possible to help us address the issue quickly.

## Thank You!

Thank you for your interest in contributing to enigoma! We appreciate your support and look forward to your contributions.
