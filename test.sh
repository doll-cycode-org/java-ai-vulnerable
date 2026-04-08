# 1. Find the hash of the first commit in the last 7 days
START_COMMIT=$(git log --since="7 days ago" --reverse --format="%H" | head -n 1)

# 2. Check if a commit was actually found
if [ -z "$START_COMMIT" ]; then
  echo "No commits found in the last 7 days."
else
  # 3. Scan from that commit (including it) to the current HEAD
  echo "Starting scan from commit: $START_COMMIT"
  cycode scan commit_history -r "$START_COMMIT^...HEAD" .
fi
