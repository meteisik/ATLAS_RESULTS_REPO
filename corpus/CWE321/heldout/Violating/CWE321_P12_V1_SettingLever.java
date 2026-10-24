import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveTask;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P12_V1_SettingLever {

    private static final class SettingLeverMaterialTask extends RecursiveTask<byte[]> {
        private final List<ByteBuffer> segments;
        private final int begin;
        private final int end;

        SettingLeverMaterialTask(List<ByteBuffer> segments, int begin, int end) {
            this.segments = segments; this.begin = begin; this.end = end;
        }

        protected byte[] compute() {
            if (end - begin == 1) {
                ByteBuffer source = segments.get(begin).asReadOnlyBuffer();
                byte[] value = new byte[source.remaining()]; source.get(value); return value;
            }
            int middle = (begin + end) / 2;
            SettingLeverMaterialTask left = new SettingLeverMaterialTask(segments, begin, middle);
            left.fork();
            byte[] rightValue = new SettingLeverMaterialTask(segments, middle, end).compute();
            byte[] leftValue = left.join();
            byte[] joined = new byte[leftValue.length + rightValue.length];
            System.arraycopy(leftValue, 0, joined, 0, leftValue.length);
            System.arraycopy(rightValue, 0, joined, leftValue.length, rightValue.length);
            return joined;
        }
    }

    private List<ByteBuffer> parcel(byte[] first, byte[] second) {
        return List.of(ByteBuffer.wrap(first).asReadOnlyBuffer(),
                ByteBuffer.wrap(second).asReadOnlyBuffer());
    }

    private byte[] combine(List<ByteBuffer> segments) {
        return ForkJoinPool.commonPool().invoke(
                new SettingLeverMaterialTask(segments, 0, segments.size()));
    }

    private SecretKeySpec construct(byte[] material) throws Exception {
        Constructor<SecretKeySpec> constructor = SecretKeySpec.class.getConstructor(
                byte[].class, String.class);
        return constructor.newInstance(material, "AES");
    }

    public SecretKeySpec matrixSettingLever() throws Exception {
        byte[] firstPart = "k20_sett".getBytes();
        byte[] secondPart = "inglever".getBytes();
        List<ByteBuffer> parcels = parcel(firstPart, secondPart);
        byte[] combined = combine(parcels);
        return construct(combined);
    }
}
