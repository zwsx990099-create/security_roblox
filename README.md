File 1: edr_core.lua — เป็นหัวใจหลักของระบบทั้งหมด ทำหน้าที่เป็น Orchestrator + Event Bus + Correlation Engine ที่ทุก module อื่นจะเชื่อมต่อเข้ามา

แนวคิดสำคัญ:

· Event Bus แบบ lock-free (ใช้ queue + worker pattern ของ Lua)
· Session management จับเวลา, fingerprint, snapshot
· Correlation Engine ที่ใช้ sliding window + graph analysis เหมือน EDR จริง
· Adaptive Threshold ปรับตาม baseline ของ environment
· ไม่พึ่ง executor ทำงานได้บน Lua 5.1 ขึ้นไป# security_roblox
