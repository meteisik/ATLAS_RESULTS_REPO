import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_MosaicHelixSafe {

    public void runMosaicHelix() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_MosaicHelixSafeSink()).queryMosaicHelix(data);
    }
}

class CWE89_P06_V1_MosaicHelixSafeSink {
    public void queryMosaicHelix(String data) throws SQLException {
        Connection mosaicHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHelix");
        Statement mosaicHelixStatement = null;
        ResultSet mosaicHelixRows = null;
        try {
            mosaicHelixStatement = mosaicHelixConnection.createStatement();
            mosaicHelixRows = mosaicHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicHelixRows.getRow());
        } finally {
            if (mosaicHelixRows != null) {
                mosaicHelixRows.close();
            }
            if (mosaicHelixStatement != null) {
                mosaicHelixStatement.close();
            }
            mosaicHelixConnection.close();
        }
    }
}
