<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>David Avatar</title>
  <style>body { margin: 0; overflow: hidden; }</style>
</head>
<body>
<script src="https://cdn.jsdelivr.net/npm/three@0.162.0/build/three.min.js"></script>
<script>
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(75, window.innerWidth/window.innerHeight, 0.1, 1000);
const renderer = new THREE.WebGLRenderer();
renderer.setSize(window.innerWidth, window.innerHeight);
document.body.appendChild(renderer.domElement);

const geometry = new THREE.SphereGeometry(1, 32, 32);
const material = new THREE.MeshStandardMaterial({color:0x00ff00});
const avatar = new THREE.Mesh(geometry, material);
scene.add(avatar);

const light = new THREE.PointLight(0xffffff, 1, 100);
light.position.set(10, 10, 10);
scene.add(light);

camera.position.z = 5;

function animate() {
    requestAnimationFrame(animate);
    avatar.rotation.y += 0.01; // simple breathing/rotation
    renderer.render(scene, camera);
}
animate();
</script>
</body>
</html>
