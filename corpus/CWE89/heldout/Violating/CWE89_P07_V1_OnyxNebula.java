import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_OnyxNebula {

    public void runOnyxNebula() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_OnyxNebulaSource()).loadOnyxNebula();
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

class CWE89_P07_V1_OnyxNebulaSource {
    public String loadOnyxNebula() {
        String data;
        data = System.getenv("ONYX_NEBULA_FILTER");
        return data;
    }
}
