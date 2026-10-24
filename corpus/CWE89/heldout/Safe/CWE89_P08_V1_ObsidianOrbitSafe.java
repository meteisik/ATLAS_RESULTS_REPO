import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_ObsidianOrbitSafe {

    public void runObsidianOrbit() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_ObsidianOrbitSafeSink()).queryObsidianOrbit(dataArray);
    }
}

class CWE89_P08_V1_ObsidianOrbitSafeSink {
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
