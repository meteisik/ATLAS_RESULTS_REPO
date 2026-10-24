import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_MosaicKestrel {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String loadMosaicKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("MOSAIC_KESTREL_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runMosaicKestrel() throws SQLException {
        String data = loadMosaicKestrel();
        Connection mosaicKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicKestrel");
        Statement mosaicKestrelStatement = null;
        ResultSet mosaicKestrelRows = null;
        try {
            mosaicKestrelStatement = mosaicKestrelConnection.createStatement();
            mosaicKestrelRows = mosaicKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicKestrelRows.getRow());
        } finally {
            if (mosaicKestrelRows != null) {
                mosaicKestrelRows.close();
            }
            if (mosaicKestrelStatement != null) {
                mosaicKestrelStatement.close();
            }
            mosaicKestrelConnection.close();
        }
    }
}
