import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_MosaicLotusSafe {

    public void runMosaicLotus() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_MosaicLotusSafeSource()).loadMosaicLotus();
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

class CWE89_P07_V1_MosaicLotusSafeSource {
    public String loadMosaicLotus() {
        String data;
        data = "foo";
        return data;
    }
}
