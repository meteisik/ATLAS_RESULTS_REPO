import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_MosaicKestrelSafe {

    public void runMosaicKestrel() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_MosaicKestrelSafeSink()).queryMosaicKestrel(data);
    }
}

class CWE89_P06_V1_MosaicKestrelSafeSink {
    public void queryMosaicKestrel(String data) throws SQLException {
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
