import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VelvetMantis {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void runVelvetMantis() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("VELVET_MANTIS_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VelvetMantisSink()).queryVelvetMantis(dataContainer);
    }
}

class CWE89_P09_V2_VelvetMantisSink {
    public void queryVelvetMantis(CWE89_P09_V2_VelvetMantis.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection velvetMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetMantis");
        Statement velvetMantisStatement = null;
        ResultSet velvetMantisRows = null;
        try {
            velvetMantisStatement = velvetMantisConnection.createStatement();
            velvetMantisRows = velvetMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetMantisRows.getRow());
        } finally {
            if (velvetMantisRows != null) {
                velvetMantisRows.close();
            }
            if (velvetMantisStatement != null) {
                velvetMantisStatement.close();
            }
            velvetMantisConnection.close();
        }
    }
}
