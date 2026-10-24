import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SaffronCascadeSafe {

    static class Container {
        public String containerOne;
    }

    public void runSaffronCascade() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SaffronCascadeSafeSink()).querySaffronCascade(dataContainer);
    }
}

class CWE89_P09_V1_SaffronCascadeSafeSink {
    public void querySaffronCascade(CWE89_P09_V1_SaffronCascadeSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection saffronCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCascade");
        Statement saffronCascadeStatement = null;
        ResultSet saffronCascadeRows = null;
        try {
            saffronCascadeStatement = saffronCascadeConnection.createStatement();
            saffronCascadeRows = saffronCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronCascadeRows.getRow());
        } finally {
            if (saffronCascadeRows != null) {
                saffronCascadeRows.close();
            }
            if (saffronCascadeStatement != null) {
                saffronCascadeStatement.close();
            }
            saffronCascadeConnection.close();
        }
    }
}
