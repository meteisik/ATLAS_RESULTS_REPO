import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_CrimsonNebula {

    private void queryCrimsonNebula(String data) throws SQLException {
        Connection crimsonNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonNebula");
        Statement crimsonNebulaStatement = null;
        ResultSet crimsonNebulaRows = null;
        try {
            crimsonNebulaStatement = crimsonNebulaConnection.createStatement();
            crimsonNebulaRows = crimsonNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonNebulaRows.getRow());
        } finally {
            if (crimsonNebulaRows != null) {
                crimsonNebulaRows.close();
            }
            if (crimsonNebulaStatement != null) {
                crimsonNebulaStatement.close();
            }
            crimsonNebulaConnection.close();
        }
    }

    public void runCrimsonNebula() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_NEBULA_FILTER");
        queryCrimsonNebula(data);
    }
}
