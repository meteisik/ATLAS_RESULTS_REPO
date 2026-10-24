import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VelvetGlint {
    private static int privateFive = 5;

    static class Container {
        public String containerOne;
    }

    public void runVelvetGlint() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("VELVET_GLINT_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VelvetGlintSink()).queryVelvetGlint(dataContainer);
    }
}

class CWE89_P09_V2_VelvetGlintSink {
    public void queryVelvetGlint(CWE89_P09_V2_VelvetGlint.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection velvetGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetGlint");
        Statement velvetGlintStatement = null;
        ResultSet velvetGlintRows = null;
        try {
            velvetGlintStatement = velvetGlintConnection.createStatement();
            velvetGlintRows = velvetGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetGlintRows.getRow());
        } finally {
            if (velvetGlintRows != null) {
                velvetGlintRows.close();
            }
            if (velvetGlintStatement != null) {
                velvetGlintStatement.close();
            }
            velvetGlintConnection.close();
        }
    }
}
