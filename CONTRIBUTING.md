# Contributing to UniVex

Thank you for your interest in contributing to UniVex! This document provides guidelines and instructions for contributing to this project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Commit Messages](#commit-messages)

## 🤝 Code of Conduct

This project adheres to ethical standards for cybersecurity research:
- Only test against authorized targets (lab environments, HTB, owned systems)
- Never use this tool for malicious purposes
- Respect privacy and data protection laws
- Report security vulnerabilities responsibly

## 🚀 Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/UnderProgress.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test thoroughly
6. Submit a pull request

## 💻 Development Setup

### Backend Setup (Python/FastAPI)

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

### Frontend Setup (Next.js/TypeScript)

```bash
cd frontend
npm install
npm run dev
```

### Docker Setup

```bash
docker-compose up -d
```

## 📁 Project Structure

```
UnderProgress/
├── backend/                 # FastAPI backend
│   ├── app/
│   │   ├── api/            # API routes
│   │   ├── core/           # Core configuration
│   │   ├── models/         # Prisma models
│   │   ├── schemas/        # Pydantic schemas
│   │   ├── services/       # Business logic
│   │   └── utils/          # Utility functions
│   ├── tests/              # Backend tests
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/               # Next.js frontend
│   ├── app/               # App router pages
│   ├── components/        # React components
│   ├── lib/              # Utilities
│   ├── public/           # Static assets
│   └── package.json
├── docs/                  # Documentation
├── docker-compose.yml
└── README.md
```

## 📝 Coding Standards

### Python (Backend)

- Follow **PEP 8** style guide
- Use **type hints** for all functions
- Maximum line length: **88 characters** (Black formatter)
- Use **async/await** for I/O operations
- Write **docstrings** for all public functions

```python
async def create_project(
    project_data: ProjectCreate,
    user_id: str
) -> Project:
    """
    Create a new penetration testing project.
    
    Args:
        project_data: Project creation data
        user_id: ID of the user creating the project
        
    Returns:
        Project: Created project instance
        
    Raises:
        ValueError: If project data is invalid
    """
    # Implementation
    pass
```

### TypeScript (Frontend)

- Follow **Airbnb TypeScript Style Guide**
- Use **strict TypeScript** configuration
- Prefer **functional components** with hooks
- Use **Server Components** by default, Client Components when needed
- Write **JSDoc comments** for complex functions

```typescript
/**
 * Create a new penetration testing project
 * @param projectData - Project creation data
 * @returns Promise resolving to created project
 */
async function createProject(projectData: ProjectCreate): Promise<Project> {
  // Implementation
}
```

### General Guidelines

- **DRY** (Don't Repeat Yourself): Extract reusable code
- **SOLID** principles for class design
- **Meaningful names**: Use descriptive variable and function names
- **Error handling**: Always handle errors gracefully
- **Security**: Never hardcode secrets, sanitize inputs

## 🧪 Testing

### Backend Testing

We use **pytest** for backend testing:

```bash
cd backend
pytest                          # Run all tests
pytest tests/test_auth.py      # Run specific test file
pytest -v                      # Verbose output
pytest --cov=app              # Coverage report
```

Test requirements:
- Minimum **80% code coverage**
- All API endpoints must have tests
- Test both success and failure cases
- Use fixtures for common setup

```python
import pytest
from app.main import app

@pytest.fixture
async def test_client():
    from httpx import AsyncClient
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

async def test_create_project(test_client):
    response = await test_client.post("/api/projects", json={...})
    assert response.status_code == 201
```

### Frontend Testing

We use **Jest** and **React Testing Library**:

```bash
cd frontend
npm test                    # Run all tests
npm test -- --coverage     # Coverage report
```

## 🔄 Pull Request Process

1. **Update documentation** if you've changed APIs
2. **Add tests** for new functionality
3. **Run linters** and fix issues:
   ```bash
   # Backend
   cd backend
   black app/              # Format code
   flake8 app/            # Lint code
   mypy app/              # Type check
   
   # Frontend
   cd frontend
   npm run lint           # ESLint
   npm run type-check     # TypeScript
   ```
4. **Ensure all tests pass**
5. **Update CHANGELOG** if applicable
6. **Reference issue numbers** in PR description
7. **Request review** from maintainers

## 📝 Commit Messages

Follow **Conventional Commits** specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(api): add project CRUD endpoints

Implement create, read, update, delete operations for projects
with JWT authentication and permission checks.

Closes #123
```

```
fix(frontend): resolve authentication redirect loop

Fixed issue where users were stuck in redirect loop after login.
Added proper token validation before redirecting.

Fixes #456
```

## 🔍 Code Review Guidelines

When reviewing PRs:
- Check for security vulnerabilities
- Verify test coverage
- Ensure code follows style guidelines
- Test functionality locally
- Provide constructive feedback

## 🐛 Bug Reports

When reporting bugs, include:
- **Description**: Clear description of the bug
- **Steps to reproduce**: Detailed steps
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Environment**: OS, Python/Node version, Docker version
- **Logs**: Relevant error messages or logs

## 💡 Feature Requests

For feature requests:
- **Use case**: Why is this feature needed?
- **Proposed solution**: How should it work?
- **Alternatives**: Other approaches considered
- **Security implications**: Any security concerns?

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Next.js Documentation](https://nextjs.org/docs)
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## ❓ Questions?

Open an issue with the `question` label or contact the maintainers.

---

**Thank you for contributing to UniVex!** 🎉
