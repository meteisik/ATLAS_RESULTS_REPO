import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianOrbitSafe {

    public void runObsidianOrbit() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianOrbitSafeSource()).loadObsidianOrbit();
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

class CWE89_P07_V1_ObsidianOrbitSafeSource {
    public String loadObsidianOrbit() {
        String data;
        data = "foo";
        return data;
    }
}
