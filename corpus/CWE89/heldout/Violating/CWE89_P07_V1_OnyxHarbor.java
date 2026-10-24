import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_OnyxHarbor {

    public void runOnyxHarbor() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_OnyxHarborSource()).loadOnyxHarbor();
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

class CWE89_P07_V1_OnyxHarborSource {
    public String loadOnyxHarbor() {
        String data;
        data = System.getenv("ONYX_HARBOR_FILTER");
        return data;
    }
}
