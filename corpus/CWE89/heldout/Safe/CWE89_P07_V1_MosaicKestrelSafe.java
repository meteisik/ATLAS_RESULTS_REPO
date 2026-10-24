import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_MosaicKestrelSafe {

    public void runMosaicKestrel() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_MosaicKestrelSafeSource()).loadMosaicKestrel();
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

class CWE89_P07_V1_MosaicKestrelSafeSource {
    public String loadMosaicKestrel() {
        String data;
        data = "foo";
        return data;
    }
}
