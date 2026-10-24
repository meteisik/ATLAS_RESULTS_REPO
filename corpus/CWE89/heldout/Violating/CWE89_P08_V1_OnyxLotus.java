import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_OnyxLotus {

    public void runOnyxLotus() throws SQLException {
        String data;
        data = System.getenv("ONYX_LOTUS_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_OnyxLotusSink()).queryOnyxLotus(dataArray);
    }
}

class CWE89_P08_V1_OnyxLotusSink {
    public void queryOnyxLotus(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection onyxLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLotus");
        Statement onyxLotusStatement = null;
        ResultSet onyxLotusRows = null;
        try {
            onyxLotusStatement = onyxLotusConnection.createStatement();
            onyxLotusRows = onyxLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxLotusRows.getRow());
        } finally {
            if (onyxLotusRows != null) {
                onyxLotusRows.close();
            }
            if (onyxLotusStatement != null) {
                onyxLotusStatement.close();
            }
            onyxLotusConnection.close();
        }
    }
}
