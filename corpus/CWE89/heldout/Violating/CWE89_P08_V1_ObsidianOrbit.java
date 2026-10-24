import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_ObsidianOrbit {

    public void runObsidianOrbit() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_ObsidianOrbitSink()).queryObsidianOrbit(dataArray);
    }
}

class CWE89_P08_V1_ObsidianOrbitSink {
    public void queryObsidianOrbit(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
