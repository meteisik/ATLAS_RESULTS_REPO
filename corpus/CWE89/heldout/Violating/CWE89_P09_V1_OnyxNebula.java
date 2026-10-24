import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_OnyxNebula {

    static class Container {
        public String containerOne;
    }

    public void runOnyxNebula() throws SQLException {
        String data;
        data = System.getenv("ONYX_NEBULA_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_OnyxNebulaSink()).queryOnyxNebula(dataContainer);
    }
}

class CWE89_P09_V1_OnyxNebulaSink {
    public void queryOnyxNebula(CWE89_P09_V1_OnyxNebula.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection onyxNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxNebula");
        Statement onyxNebulaStatement = null;
        ResultSet onyxNebulaRows = null;
        try {
            onyxNebulaStatement = onyxNebulaConnection.createStatement();
            onyxNebulaRows = onyxNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxNebulaRows.getRow());
        } finally {
            if (onyxNebulaRows != null) {
                onyxNebulaRows.close();
            }
            if (onyxNebulaStatement != null) {
                onyxNebulaStatement.close();
            }
            onyxNebulaConnection.close();
        }
    }
}
