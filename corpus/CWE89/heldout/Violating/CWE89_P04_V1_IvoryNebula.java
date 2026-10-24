import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_IvoryNebula {

    private String loadIvoryNebula() {
        String data;
        data = System.getenv("IVORY_NEBULA_FILTER");
        return data;
    }

    public void runIvoryNebula() throws SQLException {
        String data = loadIvoryNebula();
        Connection ivoryNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryNebula");
        Statement ivoryNebulaStatement = null;
        ResultSet ivoryNebulaRows = null;
        try {
            ivoryNebulaStatement = ivoryNebulaConnection.createStatement();
            ivoryNebulaRows = ivoryNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryNebulaRows.getRow());
        } finally {
            if (ivoryNebulaRows != null) {
                ivoryNebulaRows.close();
            }
            if (ivoryNebulaStatement != null) {
                ivoryNebulaStatement.close();
            }
            ivoryNebulaConnection.close();
        }
    }
}
