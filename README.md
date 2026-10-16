# Client Safety After One Year of IRONSCALES Protection: Analysis Report

**Tools:** Excel · SQL (PostgreSQL) · Power BI

> **Note:** All company names, employee records, and data used in this project are synthetic and do not reflect actual IRONSCALES customers or operations. The dataset was designed to simulate realistic IRONSCALES workflows for analytical purposes.

## Executive Summary

Phishing is widespread in professional settings, with Business Email Compromise (BEC) among its many forms. When a friend fell victim to a BEC scam, I recognized the warning signs from similar attempts I had encountered throughout my career and questioned the legitimacy of the request. This experience highlighted the need for greater awareness and stronger cybersecurity solutions, especially as AI makes phishing attacks increasingly sophisticated and automated.

IRONSCALES is an AI-powered email security and human risk management company. IRONSCALES embeds its software into cloud-based productivity suites and uses AI agents and analysts to research and protect over 18,000 organizations globally. IRONSCALES also works with a network of managed service providers (MSPs), who sell, manage, and train clients using the IRONSCALES ecosystem.

This analysis addressed the following business question:
**After a year of IRONSCALES protection, are our customers actually safer — and where is risk still concentrated?**

Across 18 customers and 12 months, the answer is yes: click rates fell 74% while report rates nearly tripled, training cuts clicks 2.5x, and roughly 90% of threats are auto-remediated in about three minutes. Remaining risk concentrates in people: high-authority departments click 3–4x more than IT, 59% of employees are repeat offenders, and a handful of accounts pair the highest click rates with the weakest training. The path forward is targeted: automated flagging of repeat offenders, role-specific training, management escalation for persistent cases, and a standing watch for emerging vectors like QR-code phishing.

## Project Context & Objectives

Acting as the data analyst at IRONSCALES, I conducted a 12-month security posture review (October 2025 – September 2026) across 18 customer companies. The objectives were to determine whether customers are getting safer, where risk is still concentrated, and how reliable the detection and response operation is, then recommend where the team should focus next.

## Data Sourcing and Preparation

This project used Muse to simulate a realistic data analysis scenario at IRONSCALES. Muse generated six CSV files containing relevant data and primary and foreign keys to support SQL queries. Initial cleaning, including duplicate removal and date standardization, was performed in Excel. The data was then queried in VS Code using SQL to answer the project questions and document additional findings. The resulting queries were imported into Power BI for visualization. One hardcoded DAX measure in Power BI solely for an individual KPI card.

| File | Rows | Contents |
|---|---|---|
| `data/customers.csv` | 18 | Customer companies: industry, size, plan, region, MSP partner, ARR |
| `data/employees.csv` | 2,505 | End users: department, title, hire date, active flag |
| `data/simulation_campaigns.csv` | 36 | Phishing simulation campaigns (3/month): theme, difficulty |
| `data/simulation_results.csv` | 60,608 | Per-employee outcome of each simulation: delivered, opened, clicked, reported |
| `data/threat_incidents.csv` | 7,500 | Detected email threats: type, severity, source, remediation time, disposition |
| `data/training_completions.csv` | 12,551 | Security awareness training assignments and completions |

## Key Findings

### 1. Are Customers Getting Safer?

Based on simulation data and legitimate threats that were addressed, customers are getting safer. Between October 2025 and September 2026, phishing click rates fell 74% (18.3% to 4.7%) while the report rate nearly tripled (7.3% to 19.9%), which means fewer people are falling for phishing, and more people are reporting it. This indicates greater vigilance among employees. When cross-referencing training completions and simulation results, the data showed that untrained employees click at 2.5x the rate of trained employees (17.8% vs 7.0%). This makes training the single biggest lever we can pull on click rate.

*Note: employee counts in this analysis exceed the 2,505 total because training status is per-campaign. For example, an employee trained in March counts as untrained for earlier campaigns. So if Employee #001 was trained in March but encountered 5 simulated phishes in January and February, they were untrained during that period, and those interactions count toward the click rate of the "untrained" group.*

As far as legitimate threats go, detection source and auto-remediation play a major role in keeping clients safe. There are four detection sources, and they handled 7,500 incidents:

- **AI Engine** — Automated scanning. Every inbound email is scored by machine learning models in real time. It picked up 4,161 incidents (the majority of all volume), 95.9% of which were automatically remediated.
- **User Report** — A suspicious email is received by an employee who then clicks the "Phish Report" button. This catches what the AI misses. It accounted for 1,808 incidents, 87.0% of which were automatically remediated.
- **Virtual SOC** — IRONSCALES' human security analysts and AI agents investigating. It handles the cases the AI Engine wasn't confident about, which is why it has the lowest auto-remediation rate. 936 incidents, 70.2% auto-remediated.
- **Threat Intel Network** — Crowdsourced threat intelligence. When one of the 18,000+ organizations confirms a threat, it is shared across the network so everyone else is protected automatically. 595 incidents, 88.6% auto-remediated.

Weighted by volume, roughly 90% of all 7,500 incidents were remediated automatically, without human touch. Auto-remediation resolves an incident in about 3.1 minutes on average, whereas manual remediation averages about 2.1 hours (126.7 minutes). The gap makes sense: analysts spend their time on the tricky incidents that bypass the automated agent, which is exactly where human judgment belongs.

<img width="1287" height="722" alt="01-are-customers-getting-safer" src="https://github.com/user-attachments/assets/60555494-7238-4c6e-be15-ea2d6a6d7d9a" />

<details>
<summary>SQL queries used </summary> 

Tracks phishing click and report rates month by month across the 12-month review period.

```sql
-- Monthly click rate and report rate trend
SELECT
    DATE_TRUNC('month', sent_date)::date AS month,
    ROUND(100.0 * SUM(clicked) / NULLIF(SUM(delivered), 0), 1) AS click_rate_percent,
    ROUND(100.0 * SUM(reported) / NULLIF(SUM(delivered), 0), 1) AS report_rate_percent
FROM simulation_results
GROUP BY month
ORDER BY month;
```

Compares click rates for employees based on whether they had completed training before each campaign was sent.

```sql
-- Click rate for trained vs untrained employees (training status per campaign)
WITH completed_training AS (
    SELECT
    employee_id,
    MIN(completed_date) AS first_completed
    FROM training_completions
    WHERE completed_date IS NOT NULL
    GROUP BY employee_id
)


SELECT
    CASE WHEN completed_training.first_completed < simulation_results.sent_date
    THEN 'Trained' ELSE 'Untrained'
    END AS training_status,
    ROUND(100.0 * SUM(simulation_results.clicked) / NULLIF(SUM(simulation_results.delivered), 0), 1) AS click_rate_percent,
    COUNT(DISTINCT simulation_results.employee_id) AS employees
FROM simulation_results
LEFT JOIN completed_training
    ON completed_training.employee_id=simulation_results.employee_id
GROUP BY training_status
ORDER BY training_status;
```

Compares average incident remediation time for automated versus manual handling, month by month.

```sql
-- Average remediation time, automated vs manual, by month
SELECT
    DATE_TRUNC('month', detected_date)::date AS month,
    CASE WHEN auto_remediated = 1 THEN 'Automated' ELSE 'Manual'
    END AS remediation_method,
    ROUND(AVG(remediation_minutes)::numeric, 1) AS average_remediation_time,
    COUNT(*) AS incidents
FROM threat_incidents
GROUP BY month,
         remediation_method
ORDER BY month,
         remediation_method;
```

Calculates the auto-remediation rate and share of total incidents for each detection source.

```sql
-- Auto-remediation rate and incident share by detection source
SELECT
    detection_source,
    ROUND(100.0 * SUM(auto_remediated) / COUNT(*), 1) AS auto_remediation_rate_percent,
    COUNT(*) as incidents,
    ROUND(100.0 * COUNT(*) / 7500, 1) AS incident_share
FROM threat_incidents
GROUP BY
    detection_source
ORDER BY
    auto_remediation_rate_percent DESC;
```

</details>

### 2. Where Is Risk Concentrated?

**Department risk:** Executives (15.5%), Finance (14.2%), and HR (13.2%) have the highest click rates, approximately 3–4 times IT's rate (4.0%). With identical simulation theme and difficulty mixes and training completion rates within 3 percentage points (78.1%–80.8%), the gap appears behavioral rather than exposure-driven. Executives also have the lowest training completion rate (78.1%), compounding their risk. Additionally, 58.9% of employees (1,475 of 2,505) clicked on at least two campaigns, indicating widespread repeat susceptibility. More than 60,000 simulations were sent, averaging approximately 24 campaigns per employee.

**Customer risk:** Of the 18 customers analyzed, Foxglove Hotels & Resorts, Meadowlark Foods, and Bluefin Media Group were identified as high-risk, combining above-average incident volumes with high click rates (10.3%–10.4%) and relatively low training completion (75%–80%). Prairie Dental Group stands out as an exception: despite the second-highest training completion rate (84.8%), it recorded the highest click rate (10.6%), suggesting a potential training effectiveness gap rather than an adoption issue.

<img width="1286" height="720" alt="02-where-is-risk-concentrated" src="https://github.com/user-attachments/assets/fb3006c7-a5ff-47b9-ade6-a8c52cfd8cee" />

**Threat trends:** The threat mix was broadly stable across the year, with one exception. QR code phishing increased approximately threefold between May and July 2026 (from around 50 to around 170 incidents per month) before receding. This resembles the QR sticker scams that affected the parking industry in 2024, where fraudulent codes were placed over legitimate parking signage until greater awareness helped address them. The pattern may reflect attackers exploiting a vulnerability at scale before filtering systems and user awareness catch up. By total volume, credential phishing led all year, with QR code phishing second only because of its concentrated surge; Business Email Compromise and malware attachments were the other persistent threats.

*Note: Table uses threat_incidents, simulation_results, and training_completions.*

<img width="1286" height="721" alt="02b-qr-code-phishing-surge" src="https://github.com/user-attachments/assets/6e4f9d1e-0661-4f5c-8d42-c25b9ce1134f" />

<details>
<summary>SQL queries used</summary>

Calculates the phishing click rate for each department to identify the highest-risk groups.

```sql
-- Click rate by department
SELECT
    employees.department,
    ROUND(100.0 * SUM(clicked) / NULLIF(SUM(delivered), 0), 1) AS click_rate_percent
FROM simulation_results
INNER JOIN employees
    ON simulation_results.employee_id=employees.employee_id
GROUP BY department
ORDER BY click_rate_percent DESC;
```

Identifies employees who clicked two or more simulations and measures their concentration within each department.

```sql
-- Repeat offenders (clicked 2+ simulations) by department
WITH repeat_offenders AS(
    SELECT
    employee_id
    FROM simulation_results
    GROUP BY employee_id
    HAVING SUM(clicked) >= 2
)


SELECT
    employees.department AS department,
    COUNT(DISTINCT repeat_offenders.employee_id) AS repeat_offenders,
    COUNT(DISTINCT employees.employee_id) AS department_headcount,
    ROUND(100.0 * COUNT(DISTINCT repeat_offenders.employee_id) / COUNT(DISTINCT employees.employee_id), 1) AS repeat_offender_percent
FROM employees
LEFT JOIN repeat_offenders
    ON repeat_offenders.employee_id=employees.employee_id
GROUP BY employees.department
ORDER BY repeat_offender_percent DESC;
```

Counts incidents by threat type and month to surface shifts such as the QR-code phishing surge.

```sql
-- Q8: Threat type volume by month (surfaces the QR-code surge)
SELECT
    DATE_TRUNC('month', detected_date)::date AS month,
    threat_type,
    COUNT(*) AS incidents
FROM threat_incidents
GROUP BY month,
         threat_type
ORDER BY month,
         incidents DESC;
```

Ranks each customer by incidents per 100 employees, click rate, and training completion to identify the highest-risk accounts.

```sql
-- Q9: Customer risk ranking across incidents, click rate, and training completion
WITH incidents_per_100 AS (
    SELECT
        customers.customer_id,
        ROUND(100.0 * COUNT(*) / MAX(customers.employee_count), 1) AS incidents_per_hundo
    FROM threat_incidents
    LEFT JOIN customers
        ON threat_incidents.customer_id=customers.customer_id
    GROUP BY customers.customer_id
    ORDER BY incidents_per_hundo DESC
    -- Ex. C016 sees 343.1 incidents for every hundred employees/inbox
),


customer_click_rate AS (
    SELECT
        customer_id,
        ROUND(100.0 * SUM(clicked) / NULLIF(SUM(delivered), 0), 1) AS click_rate_percent
    FROM simulation_results
    GROUP BY customer_id
    ORDER BY click_rate_percent DESC
    -- Customers with higher click rates have an increased likelihood of sustaining
    -- a breach
),


completion_rate_customers AS (
    SELECT
        employees.customer_id,
        ROUND(100.0 * SUM(CASE WHEN completed_date IS NOT NULL THEN 1 ELSE 0 END) / COUNT(*), 1) AS training_completion_percent
    FROM training_completions
    LEFT JOIN employees
        ON training_completions.employee_id=employees.employee_id
    GROUP BY employees.customer_id
    ORDER BY training_completion_percent DESC
    -- Percentage of employees in each company that have completed training
)


SELECT
    customers.company_name AS company_name,
    customers.employee_count AS employee_count,
    incidents_per_100.incidents_per_hundo AS incidents_per_hundred_employees,
    customer_click_rate.click_rate_percent AS click_rate_percent,
    completion_rate_customers.training_completion_percent AS training_completed_percent
FROM customers
LEFT JOIN incidents_per_100
    ON incidents_per_100.customer_id=customers.customer_id
LEFT JOIN customer_click_rate
    ON customer_click_rate.customer_id=customers.customer_id
LEFT JOIN completion_rate_customers
    ON completion_rate_customers.customer_id=customers.customer_id
ORDER BY incidents_per_100.incidents_per_hundo DESC;
```

</details>

### 3. How Reliable Is the Operation?

**Service Delivery: Direct vs. MSP-Managed**

IRONSCALES serves customers directly and through Managed Service Providers (MSPs). Across the 18 customers analyzed, 10 customers (1,460 employees) were managed directly, while eight (1,045 employees) were MSP-managed. Training completion rates were comparable at 79.8% and 80.8% respectively, and average report rates at 14.4% versus 14.2% — gaps of 1.0 and 0.2 points, with no meaningful differences to warrant action. Both service delivery models appear similarly effective based on the available data.

**Detection Accuracy and False Positives**

False positives occur when a detection source incorrectly flags legitimate activity as malicious, potentially reducing operational efficiency by diverting analysts from genuine threats. In the auto-remediation analysis, rates were 17–26 percentage points higher for detection methods other than Virtual SOC. However, false-positive rates varied considerably: User Reports had the highest rate at 14.9%, compared with 5.8% for the AI Engine, 4.9% for the Threat Intel Network, and 3.0% for Virtual SOC.

The high false-positive rate among User Reports may reflect employee vigilance, although it also presents an opportunity to improve reporting accuracy and reduce unnecessary investigation. Virtual SOC, the only method involving IRONSCALES' professional analysts reviewing ambiguous threats, had the lowest false-positive rate. This may offer an accuracy advantage, though it should be weighed against the time and resources required for manual review. Further investigation could determine whether targeted employee training can reduce false-positive reports while maintaining vigilance against genuine threats.

<img width="1285" height="725" alt="03-how-reliable-is-the-operation" src="https://github.com/user-attachments/assets/8f50b834-953c-4366-9eb9-cf95686b0af3" />


<details>
<summary>SQL queries used</summary>

Calculates the share of incidents flagged as false positives for each detection source.

```sql
-- False-positive rate by detection source
SELECT
    detection_source,
    ROUND(100.0 * SUM(CASE WHEN disposition = 'False Positive' THEN 1 ELSE 0 END) / COUNT(*), 1) AS false_positive_rate,
    COUNT(*) AS incidents
FROM threat_incidents
GROUP BY detection_source
ORDER BY false_positive_rate DESC;
```

Compares average report rates and training completion between MSP-managed and directly managed customers.

```sql
-- Report rate and training completion, MSP-managed vs direct customers
WITH report_rate AS (
    SELECT
        customer_id,
        ROUND(100.0 * SUM(reported) / NULLIF(SUM(delivered), 0), 1) AS report_rate_percent
    FROM simulation_results
    GROUP BY customer_id
),


training_rate AS (
    SELECT
        employees.customer_id,
        ROUND(100.0 * SUM(CASE WHEN training_completions.completed_date IS NOT NULL THEN 1 ELSE 0 END) / COUNT(*), 1) AS training_completed_percent
    FROM training_completions
    JOIN employees
        ON employees.employee_id = training_completions.employee_id
    GROUP BY employees.customer_id
)


SELECT
    CASE WHEN
        NULLIF(customers.managed_service_provider_partner, '') IS NULL THEN 'Direct' ELSE 'MSP-Managed'
        END AS service_method,
    ROUND(AVG(report_rate.report_rate_percent), 1) AS avg_report_rate_pct,
    ROUND(AVG(training_rate.training_completed_percent), 1) AS avg_training_completion_pct,
    COUNT(*) AS customers
FROM customers
LEFT JOIN report_rate
    ON report_rate.customer_id = customers.customer_id
LEFT JOIN training_rate
    ON training_rate.customer_id = customers.customer_id
GROUP BY service_method
ORDER BY service_method;
```

</details>

## Conclusion & Recommendation

IRONSCALES customers are meaningfully safer than a year ago: phishing click rates have fallen 74%, reporting rates have nearly tripled, training reduces click rates by 2.5x, and approximately 90% of threats are auto-remediated within three minutes.

Further improvements require targeted interventions rather than more of the same. I recommend automated tracking of repeat offenders (59% of employees clicked at least two simulations), department-level risk (Executives, Finance, and HR click at 3–4x IT's rate), and comparisons between high- and low-performing employees to identify effective training practices. These insights should inform role-specific, scenario-based training that addresses the authority and urgency cues employees encounter, rather than relying on repeated standard courses. Prairie Dental Group's 84.8% training completion rate alongside a 10.6% click rate demonstrates that completion alone does not guarantee behavioral change.

Persistent offenders should receive targeted remediation in coordination with their managers, while Foxglove Hotels & Resorts, Bluefin Media Group, and Meadowlark Foods should receive direct outreach from their account manager to address their elevated risk. Finally, the surge in QR code phishing highlights the need for ongoing emerging-threat monitoring to identify and respond to new attack vectors sooner.

_Note: ad hoc queries were used for additional context in the write-up and are not included in the "SQL queries used" sections above._
