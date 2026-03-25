type BrandVariant = "icon" | "wordmark" | "lockup";

const BRAND_ASSETS: Record<BrandVariant, {
  src: string;
  width: number;
  height: number;
  alt: string;
}> = {
  icon: {
    src: "/brand/icon.svg",
    width: 256,
    height: 256,
    alt: "OTrap brand icon",
  },
  wordmark: {
    src: "/brand/wordmark.svg",
    width: 540,
    height: 150,
    alt: "OTrap wordmark",
  },
  lockup: {
    src: "/brand/lockup.svg",
    width: 1400,
    height: 520,
    alt: "OTrap lockup",
  },
};

function dimensionsFor(variant: BrandVariant, width?: number, height?: number) {
  const asset = BRAND_ASSETS[variant];
  if (width && height) {
    return { width, height };
  }
  if (width) {
    return { width, height: Math.round((width / asset.width) * asset.height) };
  }
  if (height) {
    return { width: Math.round((height / asset.height) * asset.width), height };
  }
  return { width: asset.width, height: asset.height };
}

export function BrandMark({
  variant = "lockup",
  className,
  width,
  height,
  priority = false,
}: {
  variant?: BrandVariant;
  className?: string;
  width?: number;
  height?: number;
  priority?: boolean;
}) {
  const asset = BRAND_ASSETS[variant];
  const dimensions = dimensionsFor(variant, width, height);

  return (
    <img
      src={asset.src}
      alt={asset.alt}
      width={dimensions.width}
      height={dimensions.height}
      className={className}
      draggable={false}
      loading={priority ? "eager" : "lazy"}
      decoding="async"
      style={{
        width: `${dimensions.width}px`,
        height: `${dimensions.height}px`,
        maxWidth: "100%",
      }}
    />
  );
}
