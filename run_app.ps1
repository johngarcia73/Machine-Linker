
# CONFIG
$networkName = "redlocal"
$subnet = "172.28.0.0/16"
$imageName = "networks-project"
$dockerfilePath = "."
$containers = @("pc1", "pc2", "pc3")

# Create network if it doesn't exist
if (-not (docker network ls --format "{{.Name}}" | Select-String -Quiet "^$networkName$")) {
    Write-Host "Creating network $networkName..."
    docker network create --subnet=$subnet $networkName | Out-Null
} else {
    Write-Host "Network $networkName already exists."
}

# Building up the image
Write-Host "Building up the image $imageName..."
docker build -t $imageName -f "$dockerfilePath\Dockerfile" $dockerfilePath

# Init the containers
foreach ($c in $containers) {
    Write-Host "`nStarting containers $c..."
    docker run -d `
        --name $c `
        --network $networkName `
        -e DISPLAY=$env:DISPLAY `
        -v /tmp/.X11-unix:/tmp/.X11-unix `
        -it $imageName tail -f /dev/null
}

# Wait for them until they start
Start-Sleep -Seconds 3

# Run three terminals and execute run.py 
foreach ($c in $containers) {
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "docker exec -it $c python3 run.py"
}

