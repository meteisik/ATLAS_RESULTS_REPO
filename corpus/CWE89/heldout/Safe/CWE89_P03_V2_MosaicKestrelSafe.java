import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_MosaicKestrelSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private void queryMosaicKestrel(String data) throws SQLException {
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

    public void runMosaicKestrel() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        queryMosaicKestrel(data);
    }
}
