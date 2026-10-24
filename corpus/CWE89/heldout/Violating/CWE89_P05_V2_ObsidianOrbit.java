import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_ObsidianOrbit {

    private String obsidianOrbitData;

    private void queryObsidianOrbit() throws SQLException {
        String data = obsidianOrbitData;
        Connection obsidianOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianOrbit");
        Statement obsidianOrbitStatement = null;
        ResultSet obsidianOrbitRows = null;
        try {
            obsidianOrbitStatement = obsidianOrbitConnection.createStatement();
            obsidianOrbitRows = obsidianOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianOrbitRows.getRow());
        } finally {
            if (obsidianOrbitRows != null) {
                obsidianOrbitRows.close();
            }
            if (obsidianOrbitStatement != null) {
                obsidianOrbitStatement.close();
            }
            obsidianOrbitConnection.close();
        }
    }

    public void runObsidianOrbit() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("OBSIDIAN_ORBIT_FILTER");
            break;
        default:
            data = null;
            break;
        }
        obsidianOrbitData = data;
        queryObsidianOrbit();
    }
}
