import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_ObsidianCometSafe {

    public void runObsidianComet() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_ObsidianCometSafeSink()).queryObsidianComet(dataArray);
    }
}

class CWE89_P08_V1_ObsidianCometSafeSink {
    public void queryObsidianComet(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection obsidianCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianComet");
        Statement obsidianCometStatement = null;
        ResultSet obsidianCometRows = null;
        try {
            obsidianCometStatement = obsidianCometConnection.createStatement();
            obsidianCometRows = obsidianCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianCometRows.getRow());
        } finally {
            if (obsidianCometRows != null) {
                obsidianCometRows.close();
            }
            if (obsidianCometStatement != null) {
                obsidianCometStatement.close();
            }
            obsidianCometConnection.close();
        }
    }
}
