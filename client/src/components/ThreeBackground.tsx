import { useState, useEffect, useRef } from "react";
import * as THREE from "three";
import gsap from "gsap";

const PARTICLE_COUNT = 15000;
const SHAPE_RADIUS = 300;
const ANIMATION_DURATION = 4;

const COLORS = [
  0xFF6B6B,
  0x4ECDC4,
  0xFFE66D,
  0x95E1D3,
  0xF38181,
  0xAA96DA,
  0xFCBF49,
  0x00B4D8,
  0xE63946,
  0x2A9D8F,
];

export function ThreeBackground() {
  const mountRef = useRef<HTMLDivElement>(null);
  const [hasError, setHasError] = useState(false);

  useEffect(() => {
    if (!mountRef.current || hasError) return;

    let scene: THREE.Scene;
    let camera: THREE.PerspectiveCamera;
    let renderer: THREE.WebGLRenderer;
    let particles: THREE.Points;
    let geometry: THREE.BufferGeometry;
    let material: THREE.PointsMaterial;
    let animationId: number;
    let handleResize: () => void;
    let colorInterval: NodeJS.Timeout;
    let currentColorIndex = 0;

    try {
        scene = new THREE.Scene();
        camera = new THREE.PerspectiveCamera(
          75,
          window.innerWidth / window.innerHeight,
          0.1,
          1000
        );
        camera.position.z = 500;
    
        renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        mountRef.current.appendChild(renderer.domElement);
    
        geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(PARTICLE_COUNT * 3);
        const targetPositions = new Float32Array(PARTICLE_COUNT * 3);
    
        for (let i = 0; i < PARTICLE_COUNT; i++) {
          positions[i * 3 + 0] = Math.random() * 800 - 400;
          positions[i * 3 + 1] = Math.random() * 800 - 400;
          positions[i * 3 + 2] = Math.random() * 800 - 400;
    
          const angle = Math.random() * Math.PI * 2;
          const r = SHAPE_RADIUS + (Math.random() * 100 - 50); 
          
          targetPositions[i * 3 + 0] = Math.cos(angle) * r;
          targetPositions[i * 3 + 1] = Math.sin(angle) * r;
          targetPositions[i * 3 + 2] = (Math.random() * 100 - 50); 
        }
    
        geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute(
          "targetPosition",
          new THREE.BufferAttribute(targetPositions, 3)
        );
    
        material = new THREE.PointsMaterial({
          color: COLORS[0],
          size: 2,
          sizeAttenuation: true,
          transparent: true,
          opacity: 0.8,
          blending: THREE.AdditiveBlending,
        });
    
        particles = new THREE.Points(geometry, material);
        scene.add(particles);

        const animateColor = () => {
          currentColorIndex = (currentColorIndex + 1) % COLORS.length;
          const targetColor = new THREE.Color(COLORS[currentColorIndex]);
          
          gsap.to(material.color, {
            r: targetColor.r,
            g: targetColor.g,
            b: targetColor.b,
            duration: 2,
            ease: "power2.inOut",
          });
        };

        colorInterval = setInterval(animateColor, 3000);
    
        const positionAttribute = particles.geometry.attributes.position;
        const targetAttribute = particles.geometry.attributes.targetPosition;
    
        const morphParticles = (toCircle: boolean) => {
          if (!mountRef.current) return;

          const morphProxy = { progress: 0 };
          gsap.set(morphProxy, { progress: toCircle ? 0 : 1 });
    
          gsap.to(morphProxy, {
            progress: toCircle ? 1 : 0,
            duration: ANIMATION_DURATION,
            ease: "power2.inOut",
            onUpdate: () => {
              if (!positionAttribute) return;
              const p = morphProxy.progress;
              for (let i = 0; i < PARTICLE_COUNT * 3; i++) {
                 const randomVal = positions[i]; 
                 const ringVal = targetPositions[i]; 
                 positionAttribute.array[i] = randomVal + (ringVal - randomVal) * p;
              }
              positionAttribute.needsUpdate = true;
            },
            onComplete: () => {
              setTimeout(() => {
                if (mountRef.current) morphParticles(!toCircle);
              }, 5000); 
            },
          });
        }
    
        morphParticles(true);
    
        handleResize = () => {
          if (!camera || !renderer) return;
          camera.aspect = window.innerWidth / window.innerHeight;
          camera.updateProjectionMatrix();
          renderer.setSize(window.innerWidth, window.innerHeight);
        };
        window.addEventListener("resize", handleResize);
    
        const animate = () => {
          animationId = requestAnimationFrame(animate);
          if (particles) {
              particles.rotation.z += 0.001;
              particles.rotation.y += 0.0005;
          }
          if (renderer && scene && camera) {
              renderer.render(scene, camera);
          }
        };
        animate();

    } catch (e) {
        console.error("WebGL Error:", e);
        setHasError(true);
    }

    return () => {
      if (colorInterval) {
          clearInterval(colorInterval);
      }
      if (handleResize) {
          window.removeEventListener("resize", handleResize);
      }
      cancelAnimationFrame(animationId);
      if (mountRef.current && renderer && renderer.domElement) {
        mountRef.current.removeChild(renderer.domElement);
      }
      if (geometry) geometry.dispose();
      if (material) material.dispose();
      if (renderer) renderer.dispose();
    };
  }, [hasError]);

  if (hasError) {
      return <div className="fixed inset-0 -z-10 bg-gradient-to-br from-black to-zinc-900" />;
  }

  return <div ref={mountRef} className="fixed inset-0 -z-10 bg-black" />;
}
