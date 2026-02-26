type Props = {
  label: string;
  accept: string;
  onChange: (file: File | null) => void;
  disabled?: boolean;
  capture?: string;
};

export default function FileUpload({ label, accept, onChange, disabled, capture }: Props) {
  return (
    <label className="file-upload-label">
      {label}
      <input
        type="file"
        accept={accept}
        disabled={disabled}
        capture={capture as unknown as boolean}
        onChange={(e) => onChange(e.target.files?.[0] ?? null)}
        className="file-upload-input"
      />
    </label>
  );
}
