import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_ObsidianNebula {

    public void runObsidianNebula() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_NEBULA_FILTER");
        (new CWE89_P06_V1_ObsidianNebulaSink()).queryObsidianNebula(data);
    }
}

class CWE89_P06_V1_ObsidianNebulaSink {
    public void queryObsidianNebula(String data) throws SQLException {
        Connection obsidianNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianNebula");
        Statement obsidianNebulaStatement = null;
        ResultSet obsidianNebulaRows = null;
        try {
            obsidianNebulaStatement = obsidianNebulaConnection.createStatement();
            obsidianNebulaRows = obsidianNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianNebulaRows.getRow());
        } finally {
            if (obsidianNebulaRows != null) {
                obsidianNebulaRows.close();
            }
            if (obsidianNebulaStatement != null) {
                obsidianNebulaStatement.close();
            }
            obsidianNebulaConnection.close();
        }
    }
}
