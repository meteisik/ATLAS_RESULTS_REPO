import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_MosaicHelixSafe {

    public void runMosaicHelix() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_MosaicHelixSafeSource()).loadMosaicHelix();
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

class CWE89_P07_V1_MosaicHelixSafeSource {
    public String loadMosaicHelix() {
        String data;
        data = "foo";
        return data;
    }
}
