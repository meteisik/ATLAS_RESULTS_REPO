import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianOrbit {

    public void runObsidianOrbit() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianOrbitSource()).loadObsidianOrbit();
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
}

class CWE89_P07_V1_ObsidianOrbitSource {
    public String loadObsidianOrbit() {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_FILTER");
        return data;
    }
}
