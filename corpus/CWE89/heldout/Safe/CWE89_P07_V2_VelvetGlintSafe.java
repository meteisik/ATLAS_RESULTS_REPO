import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_VelvetGlintSafe {

    public void runVelvetGlint() throws SQLException {
        String data;
        if (5 == 5) {
            data = (new CWE89_P07_V2_VelvetGlintSafeSource()).loadVelvetGlint();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_VelvetGlintSafeSource {
    public String loadVelvetGlint() {
        String data;
        data = "foo";
        return data;
    }
}
