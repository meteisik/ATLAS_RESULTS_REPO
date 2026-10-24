import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_MosaicLotus {
    private static boolean privateReturnsTrue() { return true; }

    private String loadMosaicLotus() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("MOSAIC_LOTUS_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runMosaicLotus() throws SQLException {
        String data = loadMosaicLotus();
        Connection mosaicLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLotus");
        Statement mosaicLotusStatement = null;
        ResultSet mosaicLotusRows = null;
        try {
            mosaicLotusStatement = mosaicLotusConnection.createStatement();
            mosaicLotusRows = mosaicLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicLotusRows.getRow());
        } finally {
            if (mosaicLotusRows != null) {
                mosaicLotusRows.close();
            }
            if (mosaicLotusStatement != null) {
                mosaicLotusStatement.close();
            }
            mosaicLotusConnection.close();
        }
    }
}
