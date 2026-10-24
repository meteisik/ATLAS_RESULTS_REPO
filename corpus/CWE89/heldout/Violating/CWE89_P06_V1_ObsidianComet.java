import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_ObsidianComet {

    public void runObsidianComet() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_COMET_FILTER");
        (new CWE89_P06_V1_ObsidianCometSink()).queryObsidianComet(data);
    }
}

class CWE89_P06_V1_ObsidianCometSink {
    public void queryObsidianComet(String data) throws SQLException {
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
