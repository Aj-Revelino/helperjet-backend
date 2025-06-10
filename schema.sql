-- Create ENUM types used across tables
CREATE TYPE day_of_week AS ENUM ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday');
CREATE TYPE status_type AS ENUM ('pending', 'completed', 'incomplete');
CREATE TYPE user_type AS ENUM ('employer', 'helper');
CREATE TYPE meal_type AS ENUM ('breakfast', 'lunch', 'dinner', 'other');

-- Household table
CREATE TABLE Household (
    household_id SERIAL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Employer table
CREATE TABLE Employer (
    employer_id SERIAL PRIMARY KEY,
    household_id INTEGER NOT NULL REFERENCES Household(household_id),
    phone_number VARCHAR(20) NOT NULL UNIQUE,
    name VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Helper table
CREATE TABLE Helper (
    helper_id SERIAL PRIMARY KEY,
    household_id INTEGER NOT NULL REFERENCES Household(household_id),
    phone_number VARCHAR(20) NOT NULL UNIQUE,
    name VARCHAR(100),
    off_days JSON,  -- Using JSON for flexibility (e.g., {"days": ["Sunday"]})
    compensatory_off INTEGER,
    medical_leave INTEGER,
    mandatory_health_checkup DATE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- StandardOperatingProcedure (SOP) table
CREATE TABLE StandardOperatingProcedure (
    sop_id SERIAL PRIMARY KEY,
    household_id INTEGER NOT NULL REFERENCES Household(household_id),
    day_of_week day_of_week NOT NULL,
    task_title VARCHAR(100) NOT NULL,
    task_description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);

-- Task table
CREATE TABLE Task (
    task_id SERIAL PRIMARY KEY,
    household_id INTEGER NOT NULL REFERENCES Household(household_id),
    day_of_week day_of_week NOT NULL,
    task_title VARCHAR(100) NOT NULL,
    task_description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);

-- TaskCompletion table
CREATE TABLE TaskCompletion (
    completion_id SERIAL PRIMARY KEY,
    household_id INTEGER NOT NULL REFERENCES Household(household_id),
    sop_id INTEGER REFERENCES StandardOperatingProcedure(sop_id),
    task_id INTEGER REFERENCES Task(task_id),
    completion_date DATE NOT NULL,
    status status_type NOT NULL DEFAULT 'pending',
    photo_url VARCHAR(255),
    completed_by INTEGER REFERENCES Helper(helper_id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP,
    CONSTRAINT task_or_sop CHECK (sop_id IS NOT NULL OR task_id IS NOT NULL)  -- Ensures at least one is non-NULL
);

-- Messages table
CREATE TABLE Messages (
    message_id SERIAL PRIMARY KEY,
    household_id INTEGER NOT NULL REFERENCES Household(household_id),
    sender_id INTEGER NOT NULL,  -- Matches employer_id or helper_id
    sender_type user_type NOT NULL,
    receiver_id INTEGER NOT NULL,  -- Matches employer_id or helper_id
    receiver_type user_type NOT NULL,
    message_text TEXT NOT NULL,
    sent_at TIMESTAMP DEFAULT NOW(),
    read_at TIMESTAMP
);

-- MealPlan table
CREATE TABLE MealPlan (
    meal_plan_id SERIAL PRIMARY KEY,
    household_id INTEGER NOT NULL REFERENCES Household(household_id),
    meal_date DATE NOT NULL,
    meal_type meal_type NOT NULL,
    meal_description TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES Employer(employer_id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);
