import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_NovaSundial {

    public void runNovaSundial() throws SQLException {
        String data;
        data = System.getenv("NOVA_SUNDIAL_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_NovaSundialSink()).queryNovaSundial(dataArray);
    }
}

class CWE89_P08_V1_NovaSundialSink {
    public void queryNovaSundial(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection novaSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSundial");
        Statement novaSundialStatement = null;
        ResultSet novaSundialRows = null;
        try {
            novaSundialStatement = novaSundialConnection.createStatement();
            novaSundialRows = novaSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaSundialRows.getRow());
        } finally {
            if (novaSundialRows != null) {
                novaSundialRows.close();
            }
            if (novaSundialStatement != null) {
                novaSundialStatement.close();
            }
            novaSundialConnection.close();
        }
    }
}
