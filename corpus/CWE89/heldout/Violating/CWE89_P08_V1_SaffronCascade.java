import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_SaffronCascade {

    public void runSaffronCascade() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_CASCADE_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_SaffronCascadeSink()).querySaffronCascade(dataArray);
    }
}

class CWE89_P08_V1_SaffronCascadeSink {
    public void querySaffronCascade(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
