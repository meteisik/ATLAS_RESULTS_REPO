import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VelvetCascadeSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String containerOne;
    }

    public void runVelvetCascade() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VelvetCascadeSafeSink()).queryVelvetCascade(dataContainer);
    }
}

class CWE89_P09_V2_VelvetCascadeSafeSink {
    public void queryVelvetCascade(CWE89_P09_V2_VelvetCascadeSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection velvetCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCascade");
        Statement velvetCascadeStatement = null;
        ResultSet velvetCascadeRows = null;
        try {
            velvetCascadeStatement = velvetCascadeConnection.createStatement();
            velvetCascadeRows = velvetCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetCascadeRows.getRow());
        } finally {
            if (velvetCascadeRows != null) {
                velvetCascadeRows.close();
            }
            if (velvetCascadeStatement != null) {
                velvetCascadeStatement.close();
            }
            velvetCascadeConnection.close();
        }
    }
}
