import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_OnyxLotusSafe {

    static class Container {
        public String containerOne;
    }

    public void runOnyxLotus() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_OnyxLotusSafeSink()).queryOnyxLotus(dataContainer);
    }
}

class CWE89_P09_V1_OnyxLotusSafeSink {
    public void queryOnyxLotus(CWE89_P09_V1_OnyxLotusSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
