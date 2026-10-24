import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_NovaSundial {

    public void runNovaSundial() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_NovaSundialSource()).loadNovaSundial();
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

class CWE89_P07_V1_NovaSundialSource {
    public String loadNovaSundial() {
        String data;
        data = System.getenv("NOVA_SUNDIAL_FILTER");
        return data;
    }
}
