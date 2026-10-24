import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_OnyxHarborSafe {

    static class Container {
        public String containerOne;
    }

    public void runOnyxHarbor() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_OnyxHarborSafeSink()).queryOnyxHarbor(dataContainer);
    }
}

class CWE89_P09_V1_OnyxHarborSafeSink {
    public void queryOnyxHarbor(CWE89_P09_V1_OnyxHarborSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection onyxHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHarbor");
        Statement onyxHarborStatement = null;
        ResultSet onyxHarborRows = null;
        try {
            onyxHarborStatement = onyxHarborConnection.createStatement();
            onyxHarborRows = onyxHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxHarborRows.getRow());
        } finally {
            if (onyxHarborRows != null) {
                onyxHarborRows.close();
            }
            if (onyxHarborStatement != null) {
                onyxHarborStatement.close();
            }
            onyxHarborConnection.close();
        }
    }
}
