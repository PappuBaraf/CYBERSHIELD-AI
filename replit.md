# ContractScan - Smart Contract Risk Analysis Platform

## Overview

ContractScan is a full-stack web application that provides instant smart contract risk analysis and security scoring for Ethereum-based contracts. The platform analyzes contract bytecode, verification status, ownership patterns, and security metrics to generate comprehensive risk assessments. Users can input a contract address and receive detailed security reports including risk scores, ownership analysis, liquidity lock status, and holder distribution data.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture

**Framework**: React with TypeScript using Vite as the build tool and development server.

**UI Component System**: Shadcn UI (New York variant) built on Radix UI primitives with Tailwind CSS v4 for styling. The design system uses CSS variables for theming with a dark, cybersecurity-focused aesthetic featuring Space Grotesk and JetBrains Mono fonts.

**State Management**: TanStack Query (React Query) handles server state and API caching. Client-side routing implemented with Wouter for lightweight navigation.

**Key Design Decisions**:
- Single-page application with client-side routing
- Component-first architecture with shadcn/ui for consistent, accessible UI components
- Tailwind CSS for utility-first styling with custom theme variables
- Motion animations (Framer Motion) for enhanced user experience
- Recharts library for data visualization (pie charts, bar charts)

### Backend Architecture

**Runtime**: Node.js with Express.js web framework running in TypeScript.

**API Design**: RESTful API with dedicated endpoints:
- `POST /api/scan` - Contract analysis endpoint accepting address and chainId
- `GET /api/health` - Health check endpoint

**Build Strategy**: Custom build script using esbuild for server bundling and Vite for client bundling. Server dependencies are selectively bundled (allowlist approach) to optimize cold start times while keeping most dependencies external.

**Development vs Production**:
- Development: Vite middleware integrated into Express for HMR and live reloading
- Production: Serves pre-built static assets from dist/public directory

**Key Architectural Patterns**:
- Service-oriented architecture with separate analyzer, blockchain client, Etherscan client, and GoPlus client services
- In-memory storage implementation (MemStorage) with interface-based design allowing future database integration
- Middleware chain for JSON parsing, request logging, and error handling

### Contract Analysis System

**Multi-Source Analysis**: Aggregates data from three primary sources:
1. **Etherscan API** - Contract verification, source code, proxy detection
2. **GoPlus Security API** - Token security scores, honeypot detection, holder analysis
3. **Blockchain RPC** - Direct contract calls for ownership verification

**Risk Scoring Algorithm**: Combines multiple security metrics including:
- Contract verification status
- Proxy patterns and upgrade mechanisms
- Ownership type (EOA, Multisig, Contract, Renounced)
- Liquidity lock status and duration
- Mintability and supply change capabilities
- Holder concentration analysis
- Bytecode risk indicators

**Report Generation**: Markdown-based security reports with downloadable exports containing executive summaries, security metrics, ownership details, and risk indicators.

### Data Flow Architecture

1. User submits contract address through frontend form
2. Frontend validates Ethereum address format client-side
3. API request sent to `/api/scan` endpoint
4. Backend orchestrates parallel data fetching from Etherscan, GoPlus, and blockchain RPC
5. ContractAnalyzer service aggregates results and calculates risk score
6. Structured analysis result returned to frontend
7. Frontend renders interactive dashboard with charts, metrics, and risk indicators

### Error Handling Strategy

- Client-side validation before API calls
- Toast notifications for user-facing errors
- Graceful degradation when external APIs fail (catch blocks return null/default values)
- Comprehensive error logging on backend
- HTTP status codes for different error types (400 for validation, 500 for server errors)

## External Dependencies

### Third-Party APIs

**Etherscan API** (`process.env.ETHERSCAN_API_KEY`):
- Purpose: Contract source code verification, proxy detection, bytecode retrieval
- Endpoint: `https://api.etherscan.io/v2/api`
- Chain support: Multi-chain via chainid parameter

**GoPlus Security API** (no auth required):
- Purpose: Token security analysis, honeypot detection, holder distribution
- Endpoint: `https://api.gopluslabs.io/api/v1`
- Provides security scores, tax analysis, and ownership data

**Ethereum RPC** (`process.env.RPC_URL` or fallback to `https://eth.llamarpc.com`):
- Purpose: Direct blockchain queries for ownership verification
- Methods used: `eth_call` for contract function calls, `eth_getCode` for bytecode retrieval

### Database

**Current Implementation**: In-memory storage using Map-based MemStorage class for user data.

**Schema**: Defined in `shared/schema.ts` using Drizzle ORM with PostgreSQL dialect:
- Users table with id, username, password fields
- UUID-based primary keys with `gen_random_uuid()` default

**Future Migration Path**: Database connection configured via `process.env.DATABASE_URL` with Drizzle migrations in `./migrations` directory. The IStorage interface enables swapping MemStorage for PostgreSQL implementation without changing application logic.

### Build & Development Tools

**Vite**: Frontend build tool and dev server with HMR, custom plugins for meta image updates and Replit-specific integrations.

**Drizzle Kit**: Database schema management and migrations (configured but not actively used with current in-memory storage).

**ESBuild**: Server-side bundling with selective dependency bundling for production optimization.

**TypeScript**: Full-stack type safety with shared types between client and server via `@shared/*` path aliases.

### UI & Styling Dependencies

- Radix UI primitives for accessible component foundations
- Tailwind CSS v4 with custom theme configuration
- Lucide React for icon library
- Framer Motion for animations
- Recharts for data visualization

### Session & Authentication (Configured but Unused)

The application includes session management dependencies (connect-pg-simple, express-session) and user schema, but authentication is not implemented in the current contract scanning functionality.